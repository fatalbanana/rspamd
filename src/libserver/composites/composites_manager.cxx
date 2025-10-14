/*
 * Copyright 2025 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <memory>
#include <vector>
#include <cmath>
#include "contrib/ankerl/unordered_dense.h"

#include "composites.h"
#include "composites_internal.hxx"
#include "libserver/cfg_file.h"
#include "libserver/logger.h"
#include "libserver/maps/map.h"
#include "libutil/cxx/util.hxx"

namespace rspamd::composites {

static auto
composite_policy_from_str(const std::string_view &inp) -> enum rspamd_composite_policy
{
	const static ankerl::unordered_dense::map<std::string_view,
											  enum rspamd_composite_policy>
		names{
			{"remove", rspamd_composite_policy::RSPAMD_COMPOSITE_POLICY_REMOVE_ALL},
			{"remove_all", rspamd_composite_policy::RSPAMD_COMPOSITE_POLICY_REMOVE_ALL},
			{"default", rspamd_composite_policy::RSPAMD_COMPOSITE_POLICY_REMOVE_ALL},
			{"remove_symbol", rspamd_composite_policy::RSPAMD_COMPOSITE_POLICY_REMOVE_SYMBOL},
			{"remove_weight", rspamd_composite_policy::RSPAMD_COMPOSITE_POLICY_REMOVE_WEIGHT},
			{"leave", rspamd_composite_policy::RSPAMD_COMPOSITE_POLICY_LEAVE},
			{"remove_none", rspamd_composite_policy::RSPAMD_COMPOSITE_POLICY_LEAVE},
		};

	auto found = names.find(inp);
	if (found != names.end()) {
		return found->second;
	}

	return rspamd_composite_policy::RSPAMD_COMPOSITE_POLICY_UNKNOWN;
}// namespace rspamd::composites

auto composites_manager::add_composite(std::string_view composite_name, const ucl_object_t *obj, bool silent_duplicate) -> rspamd_composite *
{

	const auto *val = ucl_object_lookup(obj, "enabled");
	if (val != nullptr && !ucl_object_toboolean(val)) {
		msg_info_config("composite %s is disabled", composite_name.data());
		return nullptr;
	}

	if (composites.contains(composite_name)) {
		if (silent_duplicate) {
			msg_debug_config("composite %s is redefined", composite_name.data());
			return nullptr;
		}
		else {
			msg_warn_config("composite %s is redefined", composite_name.data());
		}
	}

	const char *composite_expression = nullptr;
	val = ucl_object_lookup(obj, "expression");

	if (val == NULL || !ucl_object_tostring_safe(val, &composite_expression)) {
		msg_err_config("composite must have an expression defined in %s",
					   composite_name.data());
		return nullptr;
	}

	GError *err = nullptr;
	rspamd_expression *expr = nullptr;

	if (!rspamd_parse_expression(composite_expression, 0, &composite_expr_subr,
								 NULL, cfg->cfg_pool, &err, &expr)) {
		msg_err_config("cannot parse composite expression for %s: %e",
					   composite_name.data(), err);

		if (err) {
			g_error_free(err);
		}

		return nullptr;
	}

	const auto &composite = new_composite(composite_name, expr, composite_expression);

	auto score = std::isnan(cfg->unknown_weight) ? 0.0 : cfg->unknown_weight;
	val = ucl_object_lookup(obj, "score");

	if (val != nullptr) {
		ucl_object_todouble_safe(val, &score);
	}

	/* Also set score in the metric */
	const auto *group = "composite";
	val = ucl_object_lookup(obj, "group");
	if (val != nullptr) {
		group = ucl_object_tostring(val);
	}

	const auto *description = composite_expression;
	val = ucl_object_lookup(obj, "description");
	if (val != nullptr) {
		description = ucl_object_tostring(val);
	}

	rspamd_config_add_symbol(cfg, composite_name.data(), score,
							 description, group,
							 0,
							 ucl_object_get_priority(obj), /* No +1 as it is default... */
							 1);

	const auto *elt = ucl_object_lookup(obj, "groups");
	if (elt && ucl_object_type(elt) == UCL_ARRAY) {
		const ucl_object_t *cur_gr;
		auto *gr_it = ucl_object_iterate_new(elt);

		while ((cur_gr = ucl_object_iterate_safe(gr_it, true)) != nullptr) {
			rspamd_config_add_symbol_group(cfg, composite_name.data(),
										   ucl_object_tostring(cur_gr));
		}

		ucl_object_iterate_free(gr_it);
	}

	val = ucl_object_lookup(obj, "policy");
	if (val) {
		composite->policy = composite_policy_from_str(ucl_object_tostring(val));

		if (composite->policy == rspamd_composite_policy::RSPAMD_COMPOSITE_POLICY_UNKNOWN) {
			msg_err_config("composite %s has incorrect policy", composite_name.data());
			return nullptr;
		}
	}

	return composite.get();
}

auto composites_manager::add_composite(std::string_view composite_name,
									   std::string_view composite_expression,
									   bool silent_duplicate, double score) -> rspamd_composite *
{
	GError *err = nullptr;
	rspamd_expression *expr = nullptr;

	if (composites.contains(composite_name)) {
		/* Duplicate composite - refuse to add */
		if (silent_duplicate) {
			msg_debug_config("composite %s is redefined", composite_name.data());
			return nullptr;
		}
		else {
			msg_warn_config("composite %s is redefined", composite_name.data());
		}
	}

	if (!rspamd_parse_expression(composite_expression.data(),
								 composite_expression.size(), &composite_expr_subr,
								 nullptr, cfg->cfg_pool, &err, &expr)) {
		msg_err_config("cannot parse composite expression for %s: %e",
					   composite_name.data(), err);

		if (err) {
			g_error_free(err);
		}

		return nullptr;
	}

	auto final_score = std::isnan(score) ? (std::isnan(cfg->unknown_weight) ? 0.0 : cfg->unknown_weight) : score;
	rspamd_config_add_symbol(cfg, composite_name.data(), final_score,
							 composite_name.data(), "composite",
							 0,
							 0,
							 1);

	return new_composite(composite_name, expr, composite_expression).get();
}

struct map_cbdata {
	composites_manager *cm;
	struct rspamd_config *cfg;
	std::string buf;

	explicit map_cbdata(struct rspamd_config *cfg)
		: cfg(cfg)
	{
		cm = COMPOSITE_MANAGER_FROM_PTR(cfg->composites_manager);
	}

	static char *map_read(char *chunk, int len,
						  struct map_cb_data *data,
						  gboolean _final)
	{

		if (data->cur_data == nullptr) {
			data->cur_data = data->prev_data;
			reinterpret_cast<map_cbdata *>(data->cur_data)->buf.clear();
		}

		auto *cbd = reinterpret_cast<map_cbdata *>(data->cur_data);

		cbd->buf.append(chunk, len);
		return nullptr;
	}

	static void
	map_fin(struct map_cb_data *data, void **target)
	{
		auto *cbd = reinterpret_cast<map_cbdata *>(data->cur_data);

		if (data->errored) {
			if (cbd) {
				cbd->buf.clear();
			}
		}
		else if (cbd != nullptr) {
			if (target) {
				*target = data->cur_data;
			}

			rspamd::string_foreach_line(cbd->buf, [&](std::string_view line) {
				auto [name_and_score, expr] = rspamd::string_split_on(line, ' ');
				auto [name, score] = rspamd::string_split_on(name_and_score, ':');

				if (!score.empty()) {
					/* I wish it was supported properly */
					//auto conv_res = std::from_chars(value->data(), value->size(), num);
					char numbuf[128], *endptr = nullptr;
					size_t n = std::min(score.size(), sizeof(numbuf) - 1);
					memcpy(numbuf, score.data(), n);
					numbuf[n] = '\0';
					auto num = g_ascii_strtod(numbuf, &endptr);

					if (fabs(num) >= G_MAXFLOAT || std::isnan(num)) {
						msg_err("invalid score for %*s", (int) name_and_score.size(), name_and_score.data());
						return;
					}

					auto ret = cbd->cm->add_composite(name, expr, true, num);

					if (ret == nullptr) {
						msg_err("cannot add composite %*s", (int) name_and_score.size(), name_and_score.data());
						return;
					}
				}
				else {
					msg_err("missing score for %*s", (int) name_and_score.size(), name_and_score.data());
					return;
				}
			});
		}
		else {
			msg_err("no data read for composites map");
		}
	}

	static void
	map_dtor(struct map_cb_data *data)
	{
		auto *cbd = reinterpret_cast<map_cbdata *>(data->cur_data);
		delete cbd;
	}
};
}// namespace rspamd::composites


void *
rspamd_composites_manager_create(struct rspamd_config *cfg)
{
	auto *cm = new rspamd::composites::composites_manager(cfg);

	return reinterpret_cast<void *>(cm);
}


gsize rspamd_composites_manager_nelts(void *ptr)
{
	return COMPOSITE_MANAGER_FROM_PTR(ptr)->size();
}

void *
rspamd_composites_manager_add_from_ucl(void *cm, const char *sym, const ucl_object_t *obj)
{
	return reinterpret_cast<void *>(COMPOSITE_MANAGER_FROM_PTR(cm)->add_composite(sym, obj, false));
}

void *
rspamd_composites_manager_add_from_string(void *cm, const char *sym, const char *expr)
{
	return reinterpret_cast<void *>(COMPOSITE_MANAGER_FROM_PTR(cm)->add_composite(sym, expr, false));
}

void *
rspamd_composites_manager_add_from_ucl_silent(void *cm, const char *sym, const ucl_object_t *obj)
{
	return reinterpret_cast<void *>(COMPOSITE_MANAGER_FROM_PTR(cm)->add_composite(sym, obj, true));
}

void *
rspamd_composites_manager_add_from_string_silent(void *cm, const char *sym, const char *expr)
{
	return reinterpret_cast<void *>(COMPOSITE_MANAGER_FROM_PTR(cm)->add_composite(sym, expr, true));
}


bool rspamd_composites_add_map_handlers(const ucl_object_t *obj, struct rspamd_config *cfg)
{
	auto **pcbdata = rspamd_mempool_alloc_type(cfg->cfg_pool, rspamd::composites::map_cbdata *);
	auto *cbdata = new rspamd::composites::map_cbdata{cfg};
	*pcbdata = cbdata;

	if (struct rspamd_map * m; (m = rspamd_map_add_from_ucl(cfg, obj, "composites map",
															rspamd::composites::map_cbdata::map_read, rspamd::composites::map_cbdata::map_fin,
															rspamd::composites::map_cbdata::map_dtor, (void **) pcbdata,
															nullptr, RSPAMD_MAP_DEFAULT)) == nullptr) {
		msg_err_config("cannot load composites map from %s", ucl_object_key(obj));
		return false;
	}

	return true;
}

namespace rspamd::composites {

/* Helper to check if a symbol requires second pass evaluation */
static bool
symbol_needs_second_pass(struct rspamd_config *cfg, const char *symbol_name)
{
	if (!cfg->cache) {
		return false;
	}

	auto flags = rspamd_symcache_get_symbol_flags(cfg->cache, symbol_name);

	/* Postfilters and classifiers/statistics symbols require second pass */
	return (flags & (SYMBOL_TYPE_POSTFILTER | SYMBOL_TYPE_CLASSIFIER | SYMBOL_TYPE_NOSTAT)) != 0;
}

/* Callback data for walking expression atoms to find symbol dependencies */
struct composite_dep_cbdata {
	struct rspamd_config *cfg;
	bool needs_second_pass;
	composites_manager *cm;
};

static void
composite_dep_callback(const rspamd_ftok_t *atom, gpointer ud)
{
	auto *cbd = reinterpret_cast<composite_dep_cbdata *>(ud);
	auto *cfg = cbd->cfg;

	if (cbd->needs_second_pass) {
		/* Already marked, no need to continue */
		return;
	}

	/* Convert atom to string */
	std::string_view atom_str(atom->begin, atom->len);

	/* Skip operators and special characters */
	if (atom->len == 0 || atom->begin[0] == '&' || atom->begin[0] == '|' ||
		atom->begin[0] == '!' || atom->begin[0] == '(' || atom->begin[0] == ')') {
		return;
	}

	/* Check if this is a reference to another composite */
	if (auto *dep_comp = cbd->cm->find(atom_str); dep_comp != nullptr) {
		/* Dependency on another composite - will be handled in transitive pass */
		return;
	}

	/* Check if the symbol itself needs second pass */
	/* Create null-terminated string for C API (rspamd_ftok_t is not null-terminated) */
	std::string symbol_name(atom->begin, atom->len);
	if (symbol_needs_second_pass(cfg, symbol_name.c_str())) {
		msg_debug_config("composite depends on second-pass symbol: %s",
						 symbol_name.c_str());
		cbd->needs_second_pass = true;
	}
}

void composites_manager::process_dependencies()
{
	ankerl::unordered_dense::set<rspamd_composite *> second_pass_set;
	bool changed;

	msg_debug_config("analyzing composite dependencies for two-phase evaluation");

	/* Initially, all composites start in first pass */
	for (const auto &comp: all_composites) {
		first_pass_composites.push_back(comp.get());
	}

	/* First pass: mark composites that directly depend on postfilters/stats */
	for (auto *comp: first_pass_composites) {
		composite_dep_cbdata cbd{cfg, false, this};

		rspamd_expression_atom_foreach(comp->expr,
									   composite_dep_callback,
									   &cbd);

		if (cbd.needs_second_pass) {
			second_pass_set.insert(comp);
			msg_debug_config("composite '%s' marked for second pass (direct dependency)",
							 comp->sym.c_str());
		}
	}

	/* Second pass: handle transitive dependencies */
	do {
		changed = false;
		for (auto *comp: first_pass_composites) {
			if (second_pass_set.contains(comp)) {
				continue;
			}

			bool has_second_pass_dep = false;

			/* Helper struct for lambda capture */
			struct trans_check_data {
				composites_manager *cm;
				ankerl::unordered_dense::set<rspamd_composite *> *second_pass_set;
				bool *has_dep;
			} trans_data{this, &second_pass_set, &has_second_pass_dep};

			rspamd_expression_atom_foreach(comp->expr, [](const rspamd_ftok_t *atom, gpointer ud) {
											   auto *data = reinterpret_cast<trans_check_data *>(ud);
											   std::string_view atom_str(atom->begin, atom->len);
											   if (auto *dep_comp = data->cm->find(atom_str); dep_comp != nullptr) {
												   /* Cast away const since we know this points to a modifiable composite */
												   if (data->second_pass_set->contains(const_cast<rspamd_composite *>(dep_comp))) {
													   *data->has_dep = true;
												   }
											   } }, &trans_data);

			if (has_second_pass_dep) {
				second_pass_set.insert(comp);
				changed = true;
				msg_debug_config("composite '%s' marked for second pass (transitive dependency)",
								 comp->sym.c_str());
			}
		}
	} while (changed);

	/* Move second-pass composites from first_pass to second_pass vector and mark them */
	auto it = first_pass_composites.begin();
	while (it != first_pass_composites.end()) {
		if (second_pass_set.contains(*it)) {
			(*it)->second_pass = true;
			second_pass_composites.push_back(*it);
			it = first_pass_composites.erase(it);
		}
		else {
			++it;
		}
	}

	msg_debug_config("composite dependency analysis complete: %d first-pass, %d second-pass composites",
					 (int) first_pass_composites.size(), (int) second_pass_composites.size());
}

}// namespace rspamd::composites

void rspamd_composites_process_deps(void *cm_ptr, struct rspamd_config *cfg)
{
	auto *cm = COMPOSITE_MANAGER_FROM_PTR(cm_ptr);
	cm->process_dependencies();
}