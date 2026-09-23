<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

/**
 * CircleFeed's (category 2's Facebook pick) real photo/tag-detail model --
 * see docs/research/category2-social-ugc-functionality-and-cwe-research.md
 * sec 3 item 4 and sec 6 row 1 (CC-LAB-0216/FR-LAB-123): a photo has one
 * owner and can be marked private, the same shape the real
 * `access_control`/`db_row_by_id_lookup` corpus (docs/research/corpus-
 * examples/access-control/php/) models as an order/resource fetched by its
 * primary key. This model carries no ownership check itself -- whether a
 * fetch is scoped to its owner is decided entirely by which transform op
 * gates `DbRowByIdLookupSink` (`no_ownership_check` vs.
 * `identity_match_before_fetch`), per this stack's own "sink/model is
 * neutral, the security boundary lives in the transform" convention.
 */
class Photo extends Model
{
    protected $fillable = ['owner_id', 'caption', 'image_path', 'is_private'];

    protected function casts(): array
    {
        return [
            'is_private' => 'boolean',
        ];
    }
}
